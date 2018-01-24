Function Get-DomainCredential 
{
    [CmdletBinding()]            
    Param(            
        [Parameter(            
            Mandatory = $true,            
            ParameterSetName = 'Fresh'            
        )]            
        [ValidateNotNullOrEmpty()]            
        [string[]]            
        $Domain,            
        [Parameter(            
            Mandatory = $true,            
            ParameterSetName = 'File'            
        )]            
        [Parameter(            
            Mandatory = $true,            
            ParameterSetName = 'Fresh'            
        )]            
        [ValidateNotNullOrEmpty()]            
        [string]            
        $Path            
    )            
    If ($PSBoundParameters.ContainsKey('Domain'))
    {            
        # http://www.jaapbrasser.com/quickly-and-securely-storing-your-credentials-powershell/            
        $Creds = @{}            
        ForEach ($DomainEach in $Domain)
        {            
            $username = Read-Host "enter the user for domain " $DomainEach
            $Creds[$DomainEach] = Get-Credential `
                -Message "Enter credentials for domain $DomainEach" `
                -UserName $username
        }            
        $Creds | Export-Clixml -Path $Path            
    }
    Else
    {            
        $Creds = Import-Clixml -Path $Path            
    }            
    Return $Creds            
}    
