function Invoke-CRADADA {
<#
.SYNOPSIS

Extract usefull informations from Active Directory

Author: Remi Escourrou & Nicolas Daubresse

.DESCRIPTION

Extract informations on csv that can later be imported in CRADADA

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER LdapPort

Specifies the LDAP port on which to query, defaults to 389

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER LDAPChecks

Specify the objects to dump using LDAP. Default is All.

.PARAMETER NetAPIChecks

Specify the NetAPI checks to launch. Default is None.

.PARAMETER ACL

Switch. Specify if ACL need to be retrieved. Default is no.

.PARAMETER Recurse

Switch. Determine if extraction must be done recursively. Default is no.

.PARAMETER OutputFolder

Specify the folder in which to ouput the CSV, defaults to Results.

.EXAMPLE

Invoke-CRADADA -OutputFolder CRADADA

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-CRADADA -Credential $Cred

#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        
        [ValidateSet('All', 'Computer', 'User', 'Group', 'OU', 'GPO', 'Trusts', 'GlobalObject','Printer','GUI')]
        [String[]]
        $LDAPChecks = 'All',
        
        [ValidateSet('All', 'GroupMember', 'Session', 'Share', 'StartTime', 'Version')]
        [String[]]
        $NetAPIChecks = '',
          
        [Switch]
        $ACL,
        
        [Switch]
        $Recurse,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputFolder
    )
  
    process {
        
        Write-Host "[INFO] Extracting data, this may take a while... be patient, we stay with you !" -ForegroundColor Gray 
      
        # Use current Domain if not specified
        If (-Not $PSBoundParameters['Domain']) {
            Try {
                $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            }
            Catch {
                Write-Verbose "[ERROR] Retrieving the current domain: $_"
                return $Null
            }
        }
        
        # Initialize loggin information
        $StartDate = Get-Date -format s
        
        if(!$OutputFolder) {
            $OutputFolder = (Get-Item -Path ".\").FullName + "\Results"
        }
        
        New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null
        $LogFile = $OutputFolder + "\GlobalLog.txt"
        $Log = "[INFO] " + $StartDate + ": Beginning Extraction"
        $Log | Add-Content $LogFile
        
        $Domains = New-Object System.Collections.Stack
        $Domains.Push($Domain)
        $SeenDomains = @{}
        
        while($Domains.Count -ne 0) {
            $Dom = $Domains.Pop()
        
            if ($Dom -and ($Dom.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Dom))) {
                $Null = $SeenDomains.Add($Dom, '')
                
                $DomainOutputFolder = $OutputFolder + "\" + $Dom
                New-Item -ItemType Directory -Force -Path $DomainOutputFolder | Out-Null
                
                $DomainLogFile = $DomainOutputFolder + "\Log.txt"
                $Log = "[INFO] " + $StartDate + ": Beginning Extraction on " + $Dom
                Write-Verbose $Log
                $Log | Add-Content $DomainLogFile
                
                # Store global option
                $GlobalData = @()
                $GlobalData += New-Object -TypeName psobject -Property @{Info="Domain"; Value=$Dom}
                $GlobalData += New-Object -TypeName psobject -Property @{Info="StartDate"; Value=$StartDate}

                if($Credential.UserName){
                    $UserName = $Credential.UserName
                }
                else {
                    $UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                }
                
                $GlobalData += New-Object -TypeName psobject -Property @{Info="UserName"; Value=$UserName}
                $GlobalData += New-Object -TypeName psobject -Property @{Info="LDAPChecks"; Value= $LDAPChecks -join ','}
                $GlobalData += New-Object -TypeName psobject -Property @{Info="ACL"; Value=$Acl}
                $GlobalData += New-Object -TypeName psobject -Property @{Info="NetAPIChecks"; Value= $NetAPIChecks -join ','}
                
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'Computer' ){
                    # Extract AD computers information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectClass=Computer" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = "AccountExpires","AdminCount","BadPasswordTime","BadPwdCount","CN","Description","DisplayName","DistinguishedName","IsCriticalSystemObject","LastLogon","LastLogoff","LockoutTime","LogonCount","Name","NTSecurityDescriptor","ObjectCategory","ObjectClass","ObjectGUID","ObjectSid","PwdLastSet","PrimaryGroupID","SAMAccountName","SAMAccountType","ServicePrincipalName","SIDHistory","SystemFlags","UserAccountControl","USNChanged","USNCreated","WhenChanged","WhenCreated","OperatingSystem","OperatingSystemServicePack","OperatingSystemVersion","DnsHostName","ScriptPath","ms-Mcs-AdmPwdExpirationTime"
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectClass=Computer)" -Attributes $Attributes -Class "Computers" -ACL $ACL
                    }
                    Catch {
                        Write-Verbose "[ERROR] Retrieving computers information: $_"
                    }
                }

                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'User' ){
                    # Extract AD users information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : samAccountType=805306368" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = "AccountExpires","AdminCount","BadPasswordTime","BadPwdCount","CN","Description","DisplayName","DistinguishedName","IsCriticalSystemObject","LastLogon","LastLogoff","LockoutTime","LogonCount","MemberOf","Name","NTSecurityDescriptor","ObjectCategory","ObjectClass","ObjectGUID","ObjectSid","PwdLastSet","PrimaryGroupID","SAMAccountName","SAMAccountType","ServicePrincipalName","SIDHistory","SystemFlags","UserAccountControl","UserPrincipalName","USNChanged","USNCreated","WhenChanged","WhenCreated","ScriptPath"

                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(samAccountType=805306368)" -Attributes $Attributes -Class "Users" -ACL $ACL
                    }
                    Catch {
                        Write-Verbose "[ERROR] Retrieving users information: $_"
                    }
                }
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'Group' ){
                    # Extract AD groups information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectClass=Group" 
                        $Log | Add-Content $DomainLogFile
                        Write-Verbose $Log
                    
                        $Attributes = "USNCreated","SystemFlags","IsCriticalSystemObject","GroupType","SAMAccountName","WhenChanged","ObjectSid","ObjectClass","CN","USNChanged","Name","Description","DistinguishedName","SAMAccountType","WhenCreated","InstanceType","ObjectGuid","ObjectCategory","Member","MemberOf"

                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectClass=Group)" -Attributes $Attributes -Class "Groups" -ACL $ACL
                    }
                    Catch {
                        Write-Verbose "[ERROR] Retrieving groups information: $_"
                    }
                }
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'OU' ){
                    # Extract AD OU information
                    Try {
                        $Log = "[INFO] Executing LDAP query : objectClass=organizationalunit" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile        

                        $Attributes = "Description","SystemFlags","IsCriticalSystemObject","GPLink","WhenChanged","ObjectClass","USNChanged","Name","GPOptions","DistinguishedName","OU","USNCreated","WhenCreated","InstanceType","ObjectGuid","ObjectCategory"
                    
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectClass=organizationalunit)" -Attributes $Attributes -Class "OU" -ACL $ACL
                    }
                    Catch {
                        Write-Verbose "[ERROR] Retrieving OU information: $_"
                    }
                }
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'Trusts' -or $Recurse){
                    # Extract AD trusts information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectClass=trustedDomain" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile        
                        
                        $Attributes = "TrustType","USNCreated","TrustAttributes","IsCriticalSystemObject","WhenChanged","ObjectClass","USNChanged","SecurityIdentifier","Name","CN","FlatName","ObjectCategory","DistinguishedName","TrustPartner","WhenCreated","InstanceType","ObjectGuid","TrustDirection"
                    
                        if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'Trusts'){                        
                            $Trusts = Get-LDAPTrustsInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectClass=trustedDomain)" -Attributes $Attributes -Class "Trusts" -ACL $ACL -Extract
                        } else {
                            $Trusts = Get-LDAPTrustsInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectClass=trustedDomain)" -Attributes $Attributes -Class "Trusts" -ACL $ACL 
                        }
                        
                        if($Recurse){
                            $Trusts.keys | ForEach-Object{$Domains.Push($_)}
                        }
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving trusts information: $_"
                    }
                }
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'GlobalObject' ){
                    # Extract AD Domain object information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectcategory=domain" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = $null
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectcategory=domain)" -Attributes $Attributes -Class "Domain" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving domain object information: $_"
                    }

                    # Extract AD msExchExchangeServer object information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectcategory=msExchExchangeServer" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = $null
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectcategory=msExchExchangeServer)" -Attributes $Attributes -Class  "msExchExchangeServer" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving msExchExchangeServer information: $_"
                    }

                    # Extract AD AdminSDHolder object information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : cn=AdminSDHolder" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = $null
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(cn=AdminSDHolder)" -Attributes $Attributes -Class  "AdminSDHolder" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving AdminSDHolder information: $_"
                    }

                    # Extract AD NTAuthCertificates object information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : cn=NTAuthCertificates" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = $null
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(cn=NTAuthCertificates)" -Attributes $Attributes -Class  "NTAuthCertificates" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving NTAuthCertificates information: $_"
                    }

                
                    # Extract AD msFVE-RecoveryInformation object information
                    ## a tester avec les ACL
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : class=msFVE-RecoveryInformation" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = $null
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(class=msFVE-RecoveryInformation)" -Attributes $Attributes -Class  "msFVE-RecoveryInformation" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving RecoveryInformation information: $_"
                    }
                }
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'Printer' ){
                    # Extract AD Printers object information
                    ## a tester
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectCategory=printQueue" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = "serverName","printShareName","driverName","driverVersion","portName","url","whenCreated","whenChanged","Name"
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectCategory=printQueue)" -Attributes $Attributes -Class  "printQueue" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving Printer information: $_"
                    }
                }
                
                if($ACL -or $LDAPChecks -contains 'GUI'){
                    Try {
                        $DomainTab = $Dom.Replace(".",",DC=")

                        $Log = "[INFO] Executing LDAP query : schemaIDGUID=*"
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = "cn","name","schemaIDGUID"
                        $SearchBase = "CN=Schema,CN=Configuration,DC=$DomainTab"
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(schemaIDGUID=*)" -Attributes $Attributes -Class  "schemaIDGUID" -SearchBase $SearchBase
                        
                        $Log = "[INFO] Executing LDAP query : rightsGuid=*" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = "cn","name","rightsGuid"
                        $SearchBase = "CN=Configuration,DC=$DomainTab"                
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(rightsGuid=*)" -Attributes $Attributes -Class  "controlAccessRight" -SearchBase $SearchBase
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving schemaIDGUID & rightsGuid information: $_"
                    }
                }
                
                if($LDAPChecks -contains 'All' -or $LDAPChecks -contains 'GPO' ){
                    # Extract AD GPO information
                    Try {
                    
                        $Log = "[INFO] Executing LDAP query : objectClass=grouppolicycontainer" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        $Attributes = "CN","DisplayName","DistinguishedName","Flags","GPCFileSysPath","GPCFunctionnalityVersion","GPCMachineExtensionNames","InstanceType","IsCriticalSystemObjects","Name","NTSecurityDescriptor","ObjectCategory","ObjectClass","ObjectGUID","SystemFlags","USNChanged","USNCreated","VersionNumber","WhenChanged","WhenCreated"
                        
                        Get-LDAPInfo -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Filter "(objectClass=grouppolicycontainer)" -Attributes $Attributes -Class "GPO" -ACL $ACL
                    }
                    Catch {
                      Write-Verbose "[ERROR] Retrieving GPO information: $_"
                    }

                    # Extract GPO information
                    Try {
                    
                        $Log = "[INFO] Executing GPO data extraction" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                        
                        Get-GPOInfo -Domain $Dom -OutputFolder $DomainOutputFolder
                    }
                    Catch {
                        Write-Verbose "[ERROR] Retrieving GPO data: $_"
                    } 
                }
                
                if($NetAPIChecks){
                # Extract NetApi Computer information
                    Try {
                        $Log = "[INFO] Executing NetAPI" 
                        Write-Verbose $Log
                        $Log | Add-Content $DomainLogFile
                    
                        Get-NetApiComputers -Domain $Dom -LdapPort $LdapPort -Credential $Credential -OutputFolder $DomainOutputFolder -Checks $NetAPIChecks
                    }
                    Catch {
                    Write-Verbose "[ERROR] Retrieving NET API information: $_"
                    }
                }


                $EndDate = (Get-Date -format s)
                $Time = New-Timespan -Start $StartDate -End $EndDate
                $Log = "[INFO] Extraction complete in " + $Time + " for domain " + $Dom
                Write-Host $Log -ForegroundColor Gray 
                $Log | Add-Content $DomainLogFile
                
                $GlobalData += New-Object -TypeName psobject -Property @{Info="EndDate"; Value=$EndDate}
                
                $GlobalDataPath = $DomainOutputFolder + "\GlobalData.csv"
                $GlobalData | Export-Csv -Path $GlobalDataPath -notypeinformation
                
                if(!(Test-Path -Path "$($DomainOutputFolder)\Structure") -and !(Test-Path -Path "$($DomainOutputFolder)\NetAPI")){
                    Remove-Item $DomainOutputFolder -Force -Recurse
                }
            }
        }
            
        $EndDate = (Get-Date -format s)
        $Time = New-Timespan -Start $StartDate -End $EndDate
        $Log = "[INFO] Extraction complete in " + $Time
        Write-Host $Log -ForegroundColor Gray 
        $Log | Add-Content $LogFile
    }
}


function Get-LDAPInfo {

    [CmdletBinding()]
      Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputFolder = "Results",
        
        [Parameter(Mandatory=$False)]
        [String]
        $SearchBase = $null,
        
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,
        
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Class,
        
        [String]
        $ACL,
        
        [Parameter(Mandatory=$False)]
        [String[]]
        $Attributes
    )
  
    process {
  
        $LogFile = $OutputFolder + "\Log.txt"

        $Results = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Credential -Filter $Filter -OutputFolder $OutputFolder -Attributes $Attributes -SearchBase $SearchBase
        
        if($Results){
            $OutputFile = $OutputFolder + "\Structure\$($Class).csv"
            New-Item -ItemType File -Force -Path $OutputFile | Out-Null
            

            # prepare steam writer
            $FileStream = New-Object IO.FileStream($OutputFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
            $FileWriter = New-Object System.IO.StreamWriter($FileStream)
            $FileWriter.AutoFlush = $True
        
            $Log = "[INFO][$Class] Found " + $Results.Count + " Results to query"
            $Log | Add-Content $LogFile
            Write-Verbose $Log
            
            if(!$Attributes){
                ForEach ($PropertyName in $Results.Properties.PropertyNames) {$Attributes+=$PropertyName}
            }
            
            $header = ""
            ForEach ($Attribute in $Attributes){ $header += $Attribute + ";" }
            $null = $FileWriter.WriteLine($header)
            
            foreach ($Result in $Results){
            
                $Object = ""

                ForEach ($Attribute in $Attributes){
                    $SID = 'ObjectSid', 'SIDHistory', 'SecurityIdentifier'
                    $PropertyValue = '"'
                    ForEach ($Property in $Result.Properties[$Attribute]) {
                        if ($Attribute -eq 'ObjectGuid' -or $Attribute -eq 'schemaIDGUID') {
                            # convert the GUID to a string
                            $PropertyValue = (New-Object Guid (,$Result.Properties[$Attribute][0])).Guid
                            $PropertyValue += ", "
                        }
                        elseif ($SID -match $Attribute){
                            # convert the SID to a string
                            $PropertyValue = (New-Object System.Security.Principal.SecurityIdentifier($Result.Properties[$Attribute][0],0)).Value
                            $PropertyValue += ", "
                        }
                        else{
                            $PropertyValue += $Property
                            $PropertyValue += ", "
                        }
                    }
                    
                    if($PropertyValue -ne '"'){
                        $PropertyValue = $PropertyValue.Substring(0, $PropertyValue.Length-2)
                        if ($Attribute -eq 'ObjectGuid' -or $Attribute -eq 'schemaIDGUID'){
                            $Object += $PropertyValue + ';'
                        } elseif ($SID -match $Attribute){
                            $Object += $PropertyValue + ';'
                        } else {
                            $Object += $PropertyValue + '";'
                        }
                    } else {
                        $Object += $PropertyValue + '";'
                    }
                }
                
                $null = $FileWriter.WriteLine($Object)
                [String[]] $PrepareACL +=$Result.Properties['DistinguishedName']
            }

            $FileWriter.Dispose()
            $FileStream.Dispose()
            
            $Log = "[INFO][$Class] Storing these results in " + $OutputFile
            $Log | Add-Content $LogFile
            Write-Verbose $Log
            
            if($ACL -eq "True"){
                
                $OutputFileACL = $OutputFolder + "\Structure\$($Class)_ACL.csv"
                New-Item -ItemType File -Force -Path $OutputFileACL | Out-Null
        
                Get-LDAPACL -Domain $Domain -LdapPort $LdapPort -Credential $Cred -DomainsObject $PrepareACL -OutputFileACL $OutputFileACL
                $Log = "[INFO][$Class] Storing ACL results in " + $OutputFileACL
                $Log | Add-Content $LogFile
                Write-Verbose $Log
            }
        } 
    }
}


function Get-LDAPTrustsInfo {

    [CmdletBinding()]
      Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputFolder = "Results",
        
        [Parameter(Mandatory=$False)]
        [String]
        $SearchBase = $null,
        
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,
        
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Class,
        
        [String]
        $ACL,
        
        [Parameter(Mandatory=$False)]
        [String[]]
        $Attributes,
        
        [Switch]
        $Extract
    )
  
    process {
  
        $LogFile = $OutputFolder + "\Log.txt"
        
        $Domains = New-Object System.Collections.Stack
        $Domains.Push($Domain)
        $SeenDomains = @{}
        $FirstExtract = $True
        $Count = 0
        
        # prepare steam writer
        if($Extract){
            $OutputFile = $OutputFolder + "\Structure\$($Class).csv"
            New-Item -ItemType File -Force -Path $OutputFile | Out-Null
            
            $FileStream = New-Object IO.FileStream($OutputFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
            $FileWriter = New-Object System.IO.StreamWriter($FileStream)
            $FileWriter.AutoFlush = $True
        }

        while($Domains.Count -ne 0) {
            $Dom = $Domains.Pop()
        
            if ($Dom -and ($Dom.Trim() -ne '') -and (-not $SeenDomains.ContainsKey([string]$Dom))) {
                $SeenDomains.Add([string]$Dom, '')
        
                Try{
                    $Results = Query-Objects_light -Domain $Dom -LdapPort $LdapPort -Credential $Cred -Filter $Filter -OutputFolder $OutputFolder -Attributes $Attributes -SearchBase $SearchBase
                } Catch {
                    $Results = ""
                }
                
                if($Results){
                    
                    if(!$Attributes){
                        ForEach ($PropertyName in $Results.Properties.PropertyNames) {$Attributes+=$PropertyName}
                    }
                    $Count += $Results.Count
                    
                    $header = "TrustSource;"
                    ForEach ($Attribute in $Attributes){ $header += $Attribute + ";" }
                    if($Extract -and $FirstExtract){
                        $FirstExtract = $False
                        $FileWriter.WriteLine($header)
                    }
                    
                    foreach ($Result in $Results){
                    
                        $Object = "`"$($Dom)`";"

                        ForEach ($Attribute in $Attributes){
                            $SID = 'ObjectSid', 'SIDHistory', 'SecurityIdentifier'
                            $PropertyValue = '"'
                            ForEach ($Property in $Result.Properties[$Attribute]) {
                                if ($Attribute -eq 'ObjectGuid' -or $Attribute -eq 'schemaIDGUID') {
                                    # convert the GUID to a string
                                    $PropertyValue = (New-Object Guid (,$Result.Properties[$Attribute][0])).Guid
                                    $PropertyValue += ", "
                                }
                                elseif ($SID -match $Attribute){
                                    # convert the SID to a string
                                    $PropertyValue = (New-Object System.Security.Principal.SecurityIdentifier($Result.Properties[$Attribute][0],0)).Value
                                    $PropertyValue += ", "
                                }
                                else{
                                    $PropertyValue += $Property
                                    $PropertyValue += ", "
                                }
                            }
                            
                            if($PropertyValue -ne '"'){
                                $PropertyValue = $PropertyValue.Substring(0, $PropertyValue.Length-2)
                                if ($Attribute -eq 'ObjectGuid' -or $Attribute -eq 'schemaIDGUID'){
                                    $Object += $PropertyValue + ';'
                                } elseif ($SID -match $Attribute){
                                    $Object += $PropertyValue + ';'
                                } else {
                                    $Object += $PropertyValue + '";'
                                }
                            } else {
                                $Object += $PropertyValue + '";'
                            }
                        }
                        
                        if(@("2","3").Contains([string]($Result.Properties["TrustDirection"]))){
                            $Domains.Push($Result.Properties["TrustPartner"])
                        }
                        
                        if($Extract){
                            $FileWriter.WriteLine($Object)
                        }
                        [String[]] $PrepareACL +=$Result.Properties['DistinguishedName']
                    }

                }
            }   
        }
        
                    
        $Log = "[INFO][$Class] Found " + $Count + " Results to query"
        $Log | Add-Content $LogFile
        Write-Verbose $Log
                    
        if($Extract){
            $FileWriter.Dispose()
            $FileStream.Dispose()
        
            $Log = "[INFO][$Class] Storing these results in " + $OutputFile
            $Log | Add-Content $LogFile
            Write-Verbose $Log
        }
        
        if($ACL -eq "True" -and $Extract){
            
            $OutputFileACL = $OutputFolder + "\Structure\$($Class)_ACL.csv"
            New-Item -ItemType File -Force -Path $OutputFileACL | Out-Null
    
            Get-LDAPACL -Domain $Dom -LdapPort $LdapPort -Credential $Cred -DomainsObject $PrepareACL -OutputFileACL $OutputFileACL
            $Log = "[INFO][$Class] Storing ACL results in " + $OutputFileACL
            $Log | Add-Content $LogFile
            Write-Verbose $Log
        }
        return $SeenDomains
    }
}


function Get-LDAPACL {
<#
.SYNOPSIS

Extract ACL permissions from Active Directory

Author: Remi Escourrou & Nicolas Daubresse

.DESCRIPTION

Extract informations on csv that can later be imported in CRADADA

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER DomainsObject

Specifies the object name to query ACL.

.PARAMETER LdapPort

Specifies the LDAP port on which to query, defaults to 389

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER OutputFile
Specify the file in which to ouput the CSV

.PARAMETER OutputFolder

Specify the folder in which to ouput the CSV

.EXAMPLE

Get-LDAPACL -Domain testlab.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-LDAPACL -Credential $Cred

#>

  [CmdletBinding()]
  Param(
    [Parameter(Position = 0, ValueFromPipeline = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Domain,
    
    [Parameter(Position = 1, ValueFromPipeline = $True)]
    [String[]]
    $DomainsObject,
    
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFileACL,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $LdapPort = "389",
     
    [Management.Automation.PSCredential]
    [Management.Automation.CredentialAttribute()]
    $Credential = [Management.Automation.PSCredential]::Empty,
     
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFolder = "Results"
  )
  
  process {
  
    # Use current Domain if not specified
    
    $LogFile = $OutputFolder + "\Log.txt"    
        
    $StartDate = Get-Date -format s
    $Log = "[INFO][ACL] Starting ACL Extraction" + $StartDate
    Write-Verbose $Log

    # prepare steam writer
    $FileStream = New-Object IO.FileStream($OutputFileACL, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
    $FileWriter = New-Object System.IO.StreamWriter($FileStream)
    $FileWriter.AutoFlush = $True


    $Attributes = "ObjectDN", "ObjectSid", "ActiveDirectoryRights", "BinaryLength", "AceQualifier", "IsCallback", "OpaqueLength", "AccessMask", "SecurityIdentifier", "AceType", "AceFlags", "IsInherited", "InheritanceFlags", "PropagationFlags", "AuditFlags","ObjectAceFlags","ObjectAceType","InheritedObjectAceType"
    $header = ""
    ForEach ($Attribute in $Attributes){ $header += $Attribute + ";" }
    $null = $FileWriter.WriteLine($header)
    
    $DomainsObject | Where-Object {$_} | ForEach-Object {
        
        $DomainObjectClean = $_.Replace('(', '\28').Replace(')', '\29')
        $Results = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Cred -Filter "(distinguishedname=$DomainObjectClean)" -OutputFolder $OutputFolder -SecurityMasks "Dacl"
       
                
        $Results | Where-Object {$_} | ForEach-Object {
            
            $Object = $_.Properties
            
            if ($Object['objectsid'] -ne $null) {
                $ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
            }
            else {
                $ObjectSid = $Null
            }          
            
            try {
                $ACL = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0
                
                $ACL.DiscretionaryAcl | ForEach-Object {
                    $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                    $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                    $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))

                    $Line = '"'
                    ForEach ($Attribute in $Attributes){
                        $p = $_.$Attribute
                        $Line += $p 
                        $Line += '";"'
                    }
                    $Line = $Line.Substring(0, $Line.Length-2)
                    $null = $FileWriter.WriteLine($Line)
                }
            }
            Catch {
                Write-Verbose "Error: $_"
            }
            
        }
    }
        
    $FileWriter.Dispose()
    $FileStream.Dispose()
    
    $Enddate = Get-Date -format s
    $Log = "[INFO][ACL] Ending ACL Extraction" + $Enddate
    Write-Verbose $Log
  }
}


function Get-GPOInfo {
<#
.SYNOPSIS

Extract GPO

Author: Remi Escourrou & Nicolas Daubresse

.DESCRIPTION

XX

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER OutputFolder

Specify the folder in which to ouput the CSV

.EXAMPLE

Get-GPOInfo -Domain testlab.local

.EXAMPLE

Get-GPOInfo -Credential $Cred

#>

  [CmdletBinding()]
  Param(
    [Parameter(Position = 0, ValueFromPipeline = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Domain,
     
    [Management.Automation.PSCredential]
    [Management.Automation.CredentialAttribute()]
    $Credential = [Management.Automation.PSCredential]::Empty,
     
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFolder = "Results"
  )
  
  process {

    $LogFile = $OutputFolder + "\Log.txt"
    $OutputFolderGPO = $OutputFolder + "\GPO" 
        
    New-Item -ItemType Directory -Force -Path $OutputFolderGPO | Out-Null
  
   Try {
        Import-Module GroupPolicy -Cmdlet Get-GPOReport,Get-GPOReport
        
        if(Get-Command Get-GPOReport -And Get-Command Get-GPO){

            $Log = "[INFO][GPO] Executing GPOReport query" 
            Write-Verbose $Log
            $Log | Add-Content $LogFile
            
            $GPOs = Get-GPO -All -Domain $Domain
            
            ForEach ($GPO in $GPOs){
                $GPOReport = $OutputFolderGPO  + "\" + $GPO.Id + ".xml"
                Get-GPOReport -Domain $Domain -ReportType Xml -Path $GPOReport -Guid $GPO.Id
            }
        }
    }
    Catch {
        Write-Verbose "[Error] GroupPolicy Module : $_"
    }

    Try {
        $LogFile = $OutputFolder + "\Log.txt"    
        $Log = "[INFO][GPO] Executing GPPpassword finder" 
        Write-Verbose $Log
        $Log | Add-Content $LogFile
        
        $OutputGPPPassword = $OutputFolderGPO  + "\GPPPassword.csv"
        New-Item -ItemType File -Force -Path $OutputGPPPassword | Out-Null
        
        $GPPPassword = Get-GPPPassword -Domain $Domain
        
        $GPPPassword | Export-Csv $OutputGPPPassword -NoTypeInformation -Delimiter ";"
        
    }
    Catch {
        Write-Verbose "[ERROR] GPPPassword finder: $_"
    }

    Try {
        $LogFile = $OutputFolder + "\Log.txt"    
        $Log = "[INFO][GPO] Executing GPPAutologon finder" 
        Write-Verbose $Log
        $Log | Add-Content $LogFile
        
        $OutputGPPAutologon= $OutputFolderGPO  + "\GPPAutologon.csv"
        New-Item -ItemType File -Force -Path $OutputGPPAutologon | Out-Null
        
        $GPPAutologon = Get-GPPAutologon -Domain $Domain
        
        $GPPAutologon | Export-Csv $OutputGPPAutologon -NoTypeInformation -Delimiter ";"
        
    }
    Catch {
        Write-Verbose "[ERROR] GPPAutologon finder : $_"
    }

    Try {
        $LogFile = $OutputFolder + "\Log.txt"    
        $Log = "[INFO][GPO] Executing GPPScript finder" 
        Write-Verbose $Log
        $Log | Add-Content $LogFile
        
        $OutputGPPScript= $OutputFolderGPO  + "\GPPScript.csv"
        New-Item -ItemType File -Force -Path $OutputGPPScript | Out-Null
        
        $GPPScripts = Get-GPPScript -Domain $Domain
        
        $GPPScripts | Export-Csv $OutputGPPScript -NoTypeInformation -Delimiter ";"
    }
    Catch {
        Write-Verbose "[ERROR] GPPScript finder: $_"
    }
    
    Try {
        $LogFile = $OutputFolder + "\Log.txt"    
        $Log = "[INFO][GPO] Copy GPPScript" 
        Write-Verbose $Log
        $Log | Add-Content $LogFile
        
        $OutputGPPScript = $OutputFolderGPO  + "\GPPScript"
        
        New-Item -ItemType directory $OutputGPPScript -Force | Out-Null
        
        $GPPScripts | foreach-object { if($_.ScriptOwner -notcontains "File didn't exist") {Copy-Item -Path $_.CmdLine -Destination $OutputGPPScript -Force}}

    }
    Catch {
        Write-Verbose "[ERROR] Copy GPPScript : $_"
    }
    
  }
}


function Get-NetApiComputers {
<#
.SYNOPSIS

Extract local information from computer

Author: Remi Escourrou & Nicolas Daubresse


#>

  [CmdletBinding()]
  Param(
    [Parameter(Position = 0, ValueFromPipeline = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Domain,
    
    [Parameter(Position = 1, ValueFromPipeline = $True)]
    [String[]]
    $DomainObject,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $LdapPort = "389",
     
    [Management.Automation.PSCredential]
    [Management.Automation.CredentialAttribute()]
    $Credential = [Management.Automation.PSCredential]::Empty,
    
    [Int]
    [ValidateRange(1, 100)]
    $Threads = 30,
     
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFolder = "Results",
    
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $Checks
  )
  
  process {
  
    $LogFile = $OutputFolder + "\Log.txt"    

    $LogFile = $OutputFolder + "\Log.txt"    
    $Log = "[INFO][NETAPI] Executing LDAP query : (objectClass=Computer)" 
    Write-Verbose $Log
    $Log | Add-Content $LogFile
    
    if($Checks -contains "All"){
        $Checks = "GroupMember", "Session", "Share", "StartTime", "Version"
    }
    
    foreach ($Check in $Checks) {
        $Path = $OutputFolder + "\NetAPI\Computer" + $Check + ".csv"
        New-Item -ItemType File -Force -Path $Path | Out-Null
        
        if($Check -like "GroupMember"){
            $info = "ComputerName;GroupName;MemberName;SID;IsGroup;IsDomain"
            $info | Add-Content $Path
        }
        
        if($Check -like "Session"){
            $info = "CName;UserName;Time;IdleTime;ComputerName"
            $info | Add-Content $Path
        }
        
        if($Check -like "Share"){
            $info = "shi1_netname;shi1_type;shi1_remark;ComputerName"
            $info | Add-Content $Path
        }
        
        if($Check -like "StartTime"){
            $info = "HostName;StartTime"
            $info | Add-Content $Path
        }
        
        if($Check -like "Version"){
            $info = "wki100_platform_id;wki100_computername;wki100_langroup;wki100_ver_major;wki100_ver_minor"
            $info | Add-Content $Path
        }
    }
    
 
    ## NE FONCTIONNE PAS SUR UN DOMAINE REMONTE
    ## IL FAUT ETRE DANS UN RUN AS POUR LE LANCER AVEC UN AUTRE COMPTE
    ## to do : ajouter la gestion de l'utilisateur
    
    $Attributes = "name"
    
    $Results = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Cred -Filter "(objectClass=Computer)" -OutputFolder $OutputFolder -Attributes $Attributes
    
    $Results | Where-Object {$_} | ForEach-Object {$ComputerName += $_.Properties["name"]}
    
    Write-Verbose "[INFO][NETAPI] Using threading with threads: $Threads"
    Write-Verbose "[INFO][NETAPI] TargetComputers length: $($ComputerName.Length)"
    
    # mutex so threaded code doesn't stomp on the output file
    # $Mutex = New-Object System.Threading.Mutex $False,'WriteMutex'
    
    # the host enumeration block we're using to enumerate all servers
    $HostEnumBlock = {
        Param($ComputerName,$OutputFolder,$Checks)
        
        $Mutex = New-Object System.Threading.Mutex $False,'WriteMutex'
        $FullData = @()
        
        ForEach ($TargetComputer in $ComputerName) {       
            
            $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
            
            if ($Up) {
            
                $Data = New-Object PSObject
                
                if($Checks -contains "GroupMember"){
                    $GroupMember = Get-NetLocalGroupMember -ComputerName $TargetComputer -GroupName Administrators -Method API
                    if(!$GroupMember){
                        $GroupMember = Get-NetLocalGroupMember -ComputerName $TargetComputer -GroupName Administrateurs -Method API
                    }
                    
                    $GroupMemberData = $GroupMember | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | select -Skip 1
                    $Data | Add-Member Noteproperty 'GroupMember' $GroupMemberData

                }
                
                if($Checks -contains "GroupMember"){
                    $Session = Get-NetSession -ComputerName $TargetComputer
                    $SessionData = $Session | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | select -Skip 1
                    $Data | Add-Member Noteproperty 'Session' $SessionData
                } 
                
                if($Checks -contains "Share"){
                    $Shares = Get-NetShare -ComputerName $TargetComputer
                    
                    ForEach ($Share in $Shares) {
                        $ShareName = $Share.shi1_netname
                        $Path = '\\'+$TargetComputer+'\'+$ShareName
                        if (($ShareName) -and ($ShareName.trim() -ne '')) {
                            # see if we want to check access to this share
                            # check if the user has access to this path
                            try {
                                $Null = [IO.Directory]::GetFiles($Path)
                                $ShareData = $Share | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | select -Skip 1
                                $Data | Add-Member Noteproperty 'Share' $ShareData
                            }
                            catch {
                                Write-Verbose "Error accessing share path $Path : $_"
                            }
                        }
                    }
                }
                
                if($Checks -contains "StartTime"){
                    $StartTime =  Get-NetComputerStartTime -ComputerName $TargetComputer
                    $StartTimeData = $StartTime | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | select -Skip 1
                    $Data | Add-Member Noteproperty 'StartTime' $StartTimeData
                }
                
                if($Checks -contains "Version"){
                    $Version = Get-NetComputerVersion -ComputerName $TargetComputer
                    $VersionData = $Version | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | select -Skip 1
                    $Data | Add-Member Noteproperty 'Version' $VersionData
                }
                
                if($Data){
                    $FullData+= $Data
                }
            }

            if($FullData.Count > 30){
            
                $Null = $Mutex.WaitOne()

                foreach ($Check in $Checks) {
                
                    $Path = $OutputFolder + "\NetAPI\Computer" + $Check + ".csv"
                    $FileStream = New-Object IO.FileStream($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                    $FileWriter = New-Object System.IO.StreamWriter($FileStream)
                    $FileWriter.AutoFlush = $True

                    ForEach ($Data in $FullData){
                        $Data.$Check | Where-Object {$_} | ForEach-Object {$FileWriter.WriteLine($_)}
                    }
                    
                    $FileWriter.Dispose()
                    $FileStream.Dispose()
                }
                
                $Mutex.ReleaseMutex()
                Clear-Variable $FullData
            }
        }
        
        $Null = $Mutex.WaitOne()

        foreach ($Check in $Checks) {
        
            $Path = $OutputFolder + "\NetAPI\Computer" + $Check + ".csv"
            $FileStream = New-Object IO.FileStream($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
            $FileWriter = New-Object System.IO.StreamWriter($FileStream)
            $FileWriter.AutoFlush = $True

            ForEach ($Data in $FullData){
                $Data.$Check | Where-Object {$_} | ForEach-Object {$FileWriter.WriteLine($_)}
            }
            
            $FileWriter.Dispose()
            $FileStream.Dispose()
        }
        
        $Mutex.ReleaseMutex()
        Clear-Variable $FullData
        
    }

    # if we're using threading, kick off the script block with New-ThreadedFunction
    $ScriptParams = @{
        'OutputFolder' = $OutputFolder
        'Checks' = $Checks
    }
    
    # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
    New-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
    
    $Mutex = New-Object System.Threading.Mutex $False,'WriteMutex'
    $Null = $Mutex.Dispose()
  }
}


function Query-Objects_light {
<#
.SYNOPSIS
  
Runs a LDAP Query.
Author: Remi Escourrou & Nicolas Daubresse
  
.PARAMETER Domain
  
Specifies the domain name to query for, defaults to the current domain.
  
.PARAMETER LdapPort
  
Specifies the LDAP port on which to query, defaults to 389
  
.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials 
for connection to the target domain.

.PARAMETER Filter

The ldap search filter.
If not specified, returns all objects

.PARAMETER Attributes

The list of attributes. 
If not specified, returns all attributes.

.PARAMETER Max

Maximum number of results to return. 
If not specifies, returns all results.

.DESCRIPTION

Runs and LDAP Query and returns the objects. 
It is possible to specify which attributes should be returned and the search base.

.EXAMPLE

Query-Objects_light -Domain mydomain.local -User Administrator -Password Admin123! -Filter "(&(objectCategory=User))" -Attributes Name
Get the name of all users in mydomain.local

#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
      
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        
        [ValidateSet('Dacl','Sacl')]
        [String]
        $SecurityMasks,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,
        
        [Parameter(Mandatory=$False)]
        [String]
        $SearchBase,
        
        [Parameter(Mandatory=$False)]
        [String[]]
        $Attributes,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [int]
        $Max = 1000,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputFolder
    )
    
    process {

        If (-Not $PSBoundParameters['Filter']) {
          $Filter = "(&(objectCategory=*))"
        }

        if($SearchBase){
            $SearchBase = "LDAP://$SearchBase"
        }
        else {
            $SearchBase = "LDAP://${Domain}:${LdapPort}"
        }
        

        if ($Credential.UserName -ne $null){
            $NetworkCredential = $Credential.GetNetworkCredential()
            $UserName = $NetworkCredential.UserName
            $Password = $NetworkCredential.Password
            $ObjDomain = New-Object System.DirectoryServices.DirectoryEntry $SearchBase, $UserName, $Password
        } else {
            $ObjDomain = New-Object System.DirectoryServices.DirectoryEntry $SearchBase
        }

        $Searcher = New-Object System.DirectoryServices.DirectorySearcher 
        $Searcher.SearchRoot = $ObjDomain
        $Searcher.PageSize = $Max 
        
        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        
        If ($Attributes) {
            $Searcher.PropertiesToLoad.Clear() | Out-Null
            $Searcher.PropertiesToLoad.AddRange($Attributes)
        }
        
        $Searcher.SearchScope = "Subtree"
        $Searcher.Filter = $Filter
               
        $LogFile = $OutputFolder + "\Log.txt"
       

        $Results = $Searcher.FindAll()
        return $Results
        
        Try {

        }
        Catch {
            $Log = "[-] No result found for LDAP query."
            $Log | Add-Content $LogFile
            Write-Verbose "[-] No result found for LDAP query : $_"
        }
    }
}


function New-ThreadedFunction {
    # Helper used by any threaded host enumeration functions
    # Thanks harmj0y
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    BEGIN {
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        
        # # $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        # force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope Global

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # add Functions from current runspace to the InitialSessionState
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        # Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)       
        $Pool.Open() 

        # do some trickery to get the proper BeginInvoke() method that allows for an output queue
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $ComputerName = $ComputerName | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $($ComputerName.count)"

        # partition all hosts from -ComputerName into $Threads number of groups
        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }
        
        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $Threads"

        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            # create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # add the script block + arguments with the given computer partition
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter('ComputerName', $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # kick off execution using the BeginInvok() method that allows queues
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose "[New-ThreadedFunction] Threads executing"
        # continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $SleepSeconds = 50
        Write-Verbose "[New-ThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."

        # cleanup- make sure we didn't miss anything
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $Pool.Dispose()
        Write-Verbose "[New-ThreadedFunction] all threads completed"
    }
}


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


function func {
# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


function field {
# A helper function used to reduce typing while defining struct
# fields.
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

########################################################
#
# Inspired from PowerSploit\PowerView 
# Author: @harmj0y
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
#########################################################


function Get-NetLocalGroupMember {
<#
.SYNOPSIS

Enumerates members of a specific local group on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Convert-ADName  

.DESCRIPTION

This function will enumerate the members of a specified local group  on the
current, or remote, machine. By default, the Win32 API call NetLocalGroupGetMembers
will be used (for speed). Specifying "-Method WinNT" causes the WinNT service provider
to be used instead, which returns a larger amount of information.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to "Administrators".

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with "-Method WinNT".

.EXAMPLE

Get-NetLocalGroupMember | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroupMember -Method winnt | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroup | Get-NetLocalGroupMember | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True
WINDOWS1       Guests         WINDOWS1\Guest S-1-5-21-25...          False          False
WINDOWS1       IIS_IUSRS      NT AUTHORIT... S-1-5-17                False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-4                 False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-11                False          False
WINDOWS1       Users          WINDOWS1\lo... S-1-5-21-25...          False        UNKNOWN
WINDOWS1       Users          TESTLAB\Dom... S-1-5-21-89...           True        UNKNOWN

.EXAMPLE

Get-NetLocalGroupMember -ComputerName primary.testlab.local | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
primary.tes... Administrators TESTLAB\Adm... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLAB\loc... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLAB\Ent... S-1-5-21-89...           True          False
primary.tes... Administrators TESTLAB\Dom... S-1-5-21-89...           True          False

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa370601(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq 'API') {
                # if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information

                # arguments for NetLocalGroupGetMembers
                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                # get the local user information
                $Result = $Netapi32::NetLocalGroupGetMembers($Computer, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                # locate the offset of the initial intPtr
                $Offset = $PtrInfo.ToInt64()

                $Members = @()

                # 0 = success
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ''
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $Member = New-Object PSObject
                            $Member | Add-Member Noteproperty 'ComputerName' $Computer
                            $Member | Add-Member Noteproperty 'GroupName' $GroupName
                            $Member | Add-Member Noteproperty 'MemberName' $Info.lgrmi2_domainandname
                            $Member | Add-Member Noteproperty 'SID' $SidString
                            $IsGroup = $($Info.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $Member | Add-Member Noteproperty 'IsGroup' $IsGroup
                            $Member.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            $Members += $Member
                        }
                    }

                    # free up the result buffer
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)

                    # try to extract out the machine SID by using the -500 account as a reference
                    $MachineSid = $Members | Where-Object {$_.SID -match '.*-500' -or ($_.SID -match '.*-501')} | Select-Object -Expand SID
                    if ($MachineSid) {
                        $MachineSid = $MachineSid.Substring(0, $MachineSid.LastIndexOf('-'))

                        $Members | ForEach-Object {
                            if ($_.SID -match $MachineSid) {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' $True
                            }
                        }
                    }
                    else {
                        $Members | ForEach-Object {
                            if ($_.SID -notmatch 'S-1-5-21') {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    $Members
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                # otherwise we're using the WinNT service provider
                try {
                    $GroupProvider = [ADSI]"WinNT://$Computer/$GroupName,group"

                    $GroupProvider.psbase.Invoke('Members') | ForEach-Object {

                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty 'ComputerName' $Computer
                        $Member | Add-Member Noteproperty 'GroupName' $GroupName

                        $LocalUser = ([ADSI]$_)
                        $AdsPath = $LocalUser.InvokeGet('AdsPath').Replace('WinNT://', '')
                        $IsGroup = ($LocalUser.SchemaClassName -like 'group')

                        if(([regex]::Matches($AdsPath, '/')).count -eq 1) {
                            # DOMAIN\user
                            $MemberIsDomain = $True
                            $Name = $AdsPath.Replace('/', '\')
                        }
                        else {
                            # DOMAIN\machine\user
                            $MemberIsDomain = $False
                            $Name = $AdsPath.Substring($AdsPath.IndexOf('/')+1).Replace('/', '\')
                        }

                        $Member | Add-Member Noteproperty 'AccountName' $Name
                        $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                        $Member | Add-Member Noteproperty 'IsGroup' $IsGroup
                        $Member | Add-Member Noteproperty 'IsDomain' $MemberIsDomain
                        $Member
                    }
                }
                catch {
                    Write-Verbose "[Get-NetLocalGroupMember] Error for Computer : $_"
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetShare {
<#
.SYNOPSIS

Returns open shares on the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetShareEnum Win32API call to query
a given host for open shares. This is a replacement for "net share \\hostname".

.PARAMETER ComputerName

Specifies the hostname to query for shares (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetShare

Returns active shares on the local host.

.EXAMPLE

Get-NetShare -ComputerName sqlserver

Returns active shares on the 'sqlserver' host

.EXAMPLE

Get-DomainComputer | Get-NetShare

Returns all shares for all computers in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetShare -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.ShareInfo

A PSCustomObject representing a SHARE_INFO_1 structure, including
the name/type/remark for each share, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # arguments for NetShareEnum
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get the raw share information
            $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $SHARE_INFO_1::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SHARE_INFO_1

                    # return all the sections of the structure - have to do it this way for V2
                    $Share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty 'ComputerName' $Computer
                    $Share.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Share
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetSession {
<#
.SYNOPSIS

Returns session information for the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetSessionEnum Win32API call to query
a given host for active sessions.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetSession

Returns active sessions on the local host.

.EXAMPLE

Get-NetSession -ComputerName sqlserver

Returns active sessions on the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-NetSession

Returns active sessions on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetSession -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.SessionInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the CName/UserName/Time/IdleTime for each session, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # arguments for NetSessionEnum
            $QueryLevel = 10
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get session information
            $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $SESSION_INFO_10::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SESSION_INFO_10

                    # return all the sections of the structure - have to do it this way for V2
                    $Session = $Info | Select-Object *
                    $Session | Add-Member Noteproperty 'ComputerName' $Computer
                    $Session.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Session
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }


    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetComputerStartTime{
<# 
.SYNOPSIS

Returns start time information for the local (or a remote) machine 
with domain authenticated user access.

Originally based on Benjamin Delpy's kekeo code: https://github.com/gentilkiwi/kekeo


Author: Remi Escourrou (@remiesccourrou)
License: BSD 3-Clause
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetStatisticsGet Win32API and  call to query
a given host for start time information.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetComputerStartTime

Returns start time information on the local host.

.EXAMPLE

Get-NetComputerStartTime -ComputerName sqlserver

Returns start time information on the 'sqlserver' host.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetComputerStartTime -ComputerName sqlserver -Credential $Cred

.OUTPUTS

HostName      StartTime
--------      ---------
sqlserver     18/07/2017 06:03:27

A PSCustomObject

.LINK
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
https://msdn.microsoft.com/en-us/library/windows/desktop/bb525413(v=vs.85).aspx
https://github.com/gentilkiwi/kekeo

#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    
    PROCESS {
        ForEach ($Computer in $ComputerName) {
        
            # arguments for NetStatisticsGet
            $PtrInfo = [IntPtr]::Zero
            $ServiceName = 'LanmanWorkstation'
            
            # get time information
            $Result = $Netapi32::NetStatisticsGet($Computer,$ServiceName,0,0,[ref]$PtrInfo)

            if ($Result -eq 0) {
                
                $Info = $PtrInfo -as $STAT_WORKSTATION_0               
                $StartTime = [datetime]::FromFileTime($Info.StatisticsStartTime)
                
                $ComputerStartTime = New-Object PSObject
                $ComputerStartTime | Add-Member Noteproperty 'HostName' $Computer
                $ComputerStartTime | Add-Member Noteproperty 'StartTime' $StartTime
                $ComputerStartTime | Select-object *
                                    
                # free up the result buffer
                $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
            }
            else 
            {
                Write-Verbose  "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                switch ($Result) {
                    (5)           {Write-Verbose 'The user does not have access to the requested information.'}
                    (124)         {Write-Verbose 'The value specified for the level parameter is not valid.'}
                    (53)          {Write-Verbose 'Hostname could not be found'}
                }
                
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetComputerVersion {

<#
.SYNOPSIS

Returns information about the workstation environment, including platform-specific information, 
the name of the domain and the local computer, and information concerning the operating system 
for the local (or a remote) machine with Anonymous access (if the EveryoneIncludesAnonymous policy 
setting allows anonymous access).

Author: Remi Escourrou
License: BSD 3-Clause
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetWkstaGetInfo Win32API call to query
a given host for version.

.PARAMETER ComputerName

Specifies the hostname to query for versions (also accepts IP addresses).
Defaults to 'localhost'.

.EXAMPLE

Get-NetComputerVersion

Returns information on the local host.

.EXAMPLE

Get-NetComputerVersion -ComputerName sqlserver

Returns informations on the 'sqlserver' host.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetComputerVersion -ComputerName sqlserver -Credential $Cred

.OUTPUTS

WKSTA_INFO_100

wki100_platform_id  : 500
wki100_computername : sqlserver
wki100_langroup     : TESTLAB
wki100_ver_major    : 10
wki100_ver_minor    : 0

A PSCustomObject representing a WKSTA_INFO_100 structure

.LINK
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa370663(v=vs.85).aspx

#>
    
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    
    PROCESS {
        ForEach ($Computer in $ComputerName) {
        
            # arguments for NetWkstaGetInfo
            $QueryLevel = 100
            $PtrInfo = [IntPtr]::Zero
            
            # get workstation information
            $Result = $Netapi32::NetWkstaGetInfo($Computer, $QueryLevel,[ref]$PtrInfo)
                        
            if ($Result -eq 0) {               
                $Info = $PtrInfo -as $WKSTA_INFO_100
                
                $ComputerVersion = $Info | Select-Object *
                $ComputerVersion
                
                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else 
            {
                Write-Verbose  "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                switch ($Result) {
                    (5)           {Write-Verbose 'The user does not have access to the requested information.'}
                    (124)         {Write-Verbose 'The value specified for the level parameter is not valid.'}
                    (53)          {Write-Verbose 'Hostname could not be found'}
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


$Mod = New-InMemoryModule -ModuleName Win32

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}


# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}

$SHARE_INFO_0 = struct $Mod SHARE_INFO_0 @{
    shi0_netname = field 0 String -MarshalAs @('LPWStr')
}

# enum used by $LOCALGROUP_MEMBERS_INFO_2 below
$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupEnum result structure
$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}

# the NetLocalGroupGetMembers result structure
$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}

# the NetWkstaGetInfo result structure
$WKSTA_INFO_100  = struct $Mod WKSTA_INFO_100 @{
    wki100_platform_id      = field 0 UInt32
    wki100_computername     = field 1 String -MarshalAs @('LPWStr')
    wki100_langroup         = field 2 String -MarshalAs @('LPWStr')
    wki100_ver_major        = field 3 UInt32
    wki100_ver_minor        = field 4 UInt32
}

# the NetShareEnum result structure
$TIME_OF_DAY_INFO = struct $Mod TIME_OF_DAY_INFO @{
    tod_elapsedt = field 0 UInt32
    tod_msecs = field 1 UInt32
    tod_hours = field 2 UInt32
    tod_mins = field 3 UInt32
    tod_secs = field 4 UInt32
    tod_hunds = field 5 UInt32
    tod_timezone = field 6 Int64
    tod_tinterval = field 7 UInt32
    tod_day = field 8 UInt32
    tod_month = field 9 UInt32
    tod_year = field 10 UInt32
    tod_weekday = field 11 UInt32
}

# the NetStatisticsGet result structure
$STAT_WORKSTATION_0 = struct $Mod STAT_WORKSTATION_0 @{
    StatisticsStartTime             = field 0 Int64
    BytesReceived                   = field 1 Int64
    SmbsReceived                    = field 2 Int64
    PagingReadBytesRequested        = field 3 Int64
    NonPagingReadBytesRequested     = field 4 Int64
    CacheReadBytesRequested         = field 5 Int64
    NetworkReadBytesRequested       = field 6 Int64
    BytesTransmitted                = field 7 Int64
    SmbsTransmitted                 = field 8 Int64
    PagingWriteBytesRequested       = field 9 Int64
    NonPagingWriteBytesRequested    = field 10 Int64
    CacheWriteBytesRequested        = field 11 Int64
    NetworkWriteBytesRequested      = field 12 Int64
    InitiallyFailedOperations       = field 13 UInt32
    FailedCompletionOperations      = field 14 UInt32
    ReadOperations                  = field 15 UInt32
    RandomReadOperations            = field 16 UInt32
    ReadSmbs                        = field 17 UInt32
    LargeReadSmbs                   = field 18 UInt32
    SmallReadSmbs                   = field 19 UInt32
    WriteOperations                 = field 20 UInt32
    RandomWriteOperations           = field 21 UInt32
    WriteSmbs                       = field 22 UInt32
    LargeWriteSmbs                  = field 23 UInt32
    SmallWriteSmbs                  = field 24 UInt32
    RawReadsDenied                  = field 25 UInt32
    RawWritesDenied                 = field 26 UInt32
    NetworkErrors                   = field 27 UInt32
    Sessions                        = field 28 UInt32
    FailedSessions                  = field 29 UInt32
    Reconnects                      = field 30 UInt32
    CoreConnects                    = field 31 UInt32
    Lanman20Connects                = field 32 UInt32
    Lanman21Connects                = field 33 UInt32
    LanmanNtConnects                = field 34 UInt32
    ServerDisconnects               = field 35 UInt32
    HungSessions                    = field 36 UInt32
    UseCount                        = field 37 UInt32
    FailedUseCount                  = field 38 UInt32
    CurrentCommands                 = field 39 UInt32
} 


$FunctionDefinitions = @(
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaGetInfo ([Int]) @([String], [Int], [IntPtr].MakeByRefType())),
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetStatisticsGet ([Int]) @([String],[String],[Int],[Int],[IntPtr].MakeByRefType())),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
)
   
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']


########################################################
#
# Inspired from PowerSploit\Exfiltration 
# Author: @harmj0y
#
#########################################################


function Get-GPPPassword {
    
    [CmdletBinding()]
    Param (
            [ValidateNotNullOrEmpty()]
            [String]
            $domain
    )
    
    #Some XML issues between versions
    Set-StrictMode -Version 2
    
    $XMlFiles = Get-ChildItem -Path "\\$domain\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    
    foreach ($File in $XMLFiles) {
    
        $Filename = Split-Path $File -Leaf
        [xml] $Xml = Get-Content ($File)

        #declare empty arrays
        $Cpassword = @()
        $UserName = @()
        $NewName = @()
        $Changed = @()
        $Password = @()

        #check for password field
        if ($Xml.innerxml -like "*cpassword*"){
        
            Write-Verbose "Potential password in $File"
                        
            switch ($Filename) {

                'Groups.xml' {
                    $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }

                'Services.xml' {  
                    $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }

                'Scheduledtasks.xml' {
                    $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }

                'DataSources.xml' { 
                    $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                }
                
                'Printers.xml' { 
                    $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }

                'Drives.xml' { 
                    $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                }
            }
       }

       
       foreach ($Pass in $Cpassword) {
           $Password += , $Pass
       }
        
        #put [BLANK] in variables
        if (!($Password)) {$Password = '[BLANK]'}
        if (!($UserName)) {$UserName = '[BLANK]'}
        if (!($Changed)) {$Changed = '[BLANK]'}
        if (!($NewName)) {$NewName = '[BLANK]'}
              
        #Create custom object to output results
        $ObjectProperties = @{'Passwords' = $Password;
                              'UserNames' = $UserName;
                              'Changed' = $Changed;
                              'NewName' = $NewName;
                              'File' = $File}
            
        $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties

        if ($ResultsObject) {Return $ResultsObject} 
    }
}


function Get-GPPAutologon {


    [CmdletBinding()]
    Param (
            [ValidateNotNullOrEmpty()]
            [String]
            $domain
    )
    
    #Some XML issues between versions
    Set-StrictMode -Version 2
    
    $XMlFiles = Get-ChildItem -Path "\\$domain\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Registry.xml'
    
    foreach ($File in $XMLFiles) {
        $Filename = Split-Path $File -Leaf
        [xml] $Xml = Get-Content ($File)

        #declare empty arrays
        $Password = @()
        $UserName = @()
        
        #check for password and username field
        if (($Xml.innerxml -like "*DefaultPassword*") -and ($Xml.innerxml -like "*DefaultUserName*"))
        {            
            $props = $xml.GetElementsByTagName("Properties")
            foreach($prop in $props)
            {
                switch ($prop.name) 
                {
                    'DefaultPassword'
                    {
                        $Password += , $prop | Select-Object -ExpandProperty Value
                    }
                
                    'DefaultUsername'
                    {
                        $Username += , $prop | Select-Object -ExpandProperty Value
                    }
            }

                Write-Verbose "Potential password in $File"
            }
                     
            #put [BLANK] in variables
            if (!($Password)) 
            {
                $Password = '[BLANK]'
            }

            if (!($UserName))
            {
                $UserName = '[BLANK]'
            }
                   
            #Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'File' = $File}
                
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            
            if ($ResultsObject)
            {
                $ResultsObject
            }
        }
    }
}



########################################################
# 
# Remi ESCOURROU
# Inspired from Groupers
# 
# Requires -Version 2.0 
# 
#########################################################


function Get-GPPScript {   

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $domain
    )
    
    $IniFiles = @()
    
    Get-ChildItem -Path "\\$domain\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Force -Include '*scripts.ini'  | Foreach-Object {$IniFiles +=$_.FullName}
    
    $attributes = "FullControl","TakeOwnership","Modify","Write","WriteData","WriteAttributes"
    
    $GPPScripts = @()
    
    foreach ($IniFile in $IniFiles){
        $FileContent = Get-IniContent $IniFile
        foreach ($key in $FileContent.Keys){

            if (($key -like "*logon*") -or ($key -like "*logoff*") -or ($key -like "*Shutdown*") -or ($key -like "*startup*")){
                
                $numberCmd = $fileContent[$key].keys.Count / 2 - 1
                    
                for ($Count = 0; $Count -le $numberCmd; $Count++){
                    
                    $currentCmdLine = [String]$Count + "CmdLine"
                    $currentParameters = [String]$Count + "Parameters"
                    
                    $GPPScript = New-Object PSObject 
                    $GPPScript | Add-Member Noteproperty 'IniFile' $IniFile
                    $GPO = ([string]$IniFile).split("\")
                    $GPPScript | Add-Member Noteproperty 'GPO' $GPO[6]
                    $GPPScript | Add-Member Noteproperty 'Key' $key
                    $GPPScript | Add-Member Noteproperty 'CmdLine' $fileContent[$key][$currentCmdLine]
                    $GPPScript | Add-Member Noteproperty 'Parameters' $fileContent[$key][$currentParameters]

                    
                    if ($fileContent[$key][$currentCmdLine].StartsWith("\\")){
                        
                        $FullControl = ""
                        $TakeOwnership = ""
                        $Modify = ""
                        $Write = ""
                        $WriteData = ""
                        $WriteAttributes = ""
                            
                        If ((Test-Path $fileContent[$key][$currentCmdLine])){
                            $ACL = Get-Acl -Path $fileContent[$key][$currentCmdLine]
                            $ACl.Access | Where-Object { $_.AccessControlType -like "Allow" } | Foreach-Object {
                                if ($_.FileSystemRights -like "*FullControl*"){$FullControl += $_.IdentityReference.Value + ","}
                                if ($_.FileSystemRights -like "*TakeOwnership*"){$TakeOwnership += $_.IdentityReference.Value + ","}
                                if ($_.FileSystemRights -like "*Modify*"){$Modify += [String]$_.IdentityReference + ","}
                                if ($_.FileSystemRights -like "*Write*"){$Write += [String]$_.IdentityReference + ","}
                                if ($_.FileSystemRights -like "*WriteData*"){$WriteData += [String]$_.IdentityReference + ","}
                                if ($_.FileSystemRights -like "*WriteAttributes*"){$WriteAttributes += [String]$_.IdentityReference + ","}
                            }
                            $GPPScript | Add-Member Noteproperty 'ScriptOwner' $ACL.Owner
                            
                        }
                        else {
                             $GPPScript | Add-Member Noteproperty 'ScriptOwner' "File didn't exist"
                        }
                        
                        $GPPScript | Add-Member Noteproperty 'Script_FullControl' $FullControl
                        $GPPScript | Add-Member Noteproperty 'Script_TakeOwnership' $TakeOwnership
                        $GPPScript | Add-Member Noteproperty 'Script_Modify' $Modify
                        $GPPScript | Add-Member Noteproperty 'Script_Write' $Write
                        $GPPScript | Add-Member Noteproperty 'Script_WriteData' $WriteData
                        $GPPScript | Add-Member Noteproperty 'Script_WriteAttributes' $WriteAttributes
                        
                        $GPPScripts += $GPPScript
 
                    }
                }
            }
        }
    }
    $GPPScripts
}


########################################################
#
# From https://github.com/lipkau/PsIni 
# Author: Oliver Lipkau
#
#########################################################

Function Get-IniContent {  
    <#  
    .Synopsis  
        Gets the content of an INI file  
          
    .Description  
        Gets the content of an INI file and returns it as a hashtable  
          
    .Notes  
        Author        : Oliver Lipkau <oliver@lipkau.net>  
        Blog        : http://oliver.lipkau.net/blog/  
        Source        : https://github.com/lipkau/PsIni 
                      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91 
        Version        : 1.0 - 2010/03/12 - Initial release  
                      1.1 - 2014/12/11 - Typo (Thx SLDR) 
                                         Typo (Thx Dave Stiff) 
          
        #Requires -Version 2.0  
          
    .Inputs  
        System.String  
          
    .Outputs  
        System.Collections.Hashtable  
          
    .Parameter FilePath  
        Specifies the path to the input file.  
          
    .Example  
        $FileContent = Get-IniContent "C:\myinifile.ini"  
        -----------  
        Description  
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent  
      
    .Example  
        $inifilepath | $FileContent = Get-IniContent  
        -----------  
        Description  
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent  
      
    .Example  
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini"  
        C:\PS>$FileContent["Section"]["Key"]  
        -----------  
        Description  
        Returns the key "Key" of the section "Section" from the C:\settings.ini file  
          
    .Link  
        Out-IniFile  
    #>  
      
    [CmdletBinding()]  
    Param(  
        [ValidateNotNullOrEmpty()]  
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]  
        [string]$FilePath
    )  
      
    #Begin  
    #    {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}  
          
    Process  
    {  
        #Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"  
              
        $ini = @{}  
        switch -regex -file $FilePath  
        {  
            "^\[(.+)\]$" # Section  
            {  
                $section = $matches[1]  
                $ini[$section] = @{}  
                $CommentCount = 0  
            }  
            "^(;.*)$" # Comment  
            {  
                if (!($section))  
                {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $value = $matches[1]  
                $CommentCount = $CommentCount + 1  
                $name = "Comment" + $CommentCount  
                $ini[$section][$name] = $value  
            }   
            "(.+?)\s*=\s*(.*)" # Key  
            {  
                if (!($section))  
                {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $name,$value = $matches[1..2]  
                $ini[$section][$name] = $value  
            }  
        }  
        #Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"  
        Return $ini  
    }  
          
    #End  
    #    {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}  
} 