
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