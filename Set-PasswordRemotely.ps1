function Set-PasswordRemotely {

	## Change a password on a remote forest. 
	## Used Get-Credential to avoid password in PSReadLine
	## The method above is actually based on NetUserChangePassword function.
	
	## Inspired from @chryzsh
	## https://gist.github.com/chryzsh/f814a3d6088c5bc8f1adfafce2eb3779
	
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)][alias('DC', 'Server', 'ComputerName')][string] $DomainController
    )
	
    $DllImport = @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
public static extern bool NetUserChangePassword(string domain, string username, string oldpassword, string newpassword);
'@

    $NetApi32 = Add-Type -MemberDefinition $DllImport -Name 'NetApi32' -Namespace 'Win32' -PassThru

    $OldPasswordSecure = Get-Credential $UserName -Message "OldPassword"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($OldPasswordSecure.Password)
    $OldPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $NewPasswordSecure = Get-Credential $UserName -Message "NewPassword"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPasswordSecure.Password)
    $NewPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    if ($result = $NetApi32::NetUserChangePassword($DomainController, $UserName, $OldPassword, $NewPassword)) {
        Write-Output -InputObject 'Password change failed. Please try again.'
    } else {
        Write-Output -InputObject 'Password change succeeded.'
    }
}