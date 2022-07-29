
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
        $Max = 1000

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

        $Results = $Searcher.FindAll()
        return $Results
        
    }
}

