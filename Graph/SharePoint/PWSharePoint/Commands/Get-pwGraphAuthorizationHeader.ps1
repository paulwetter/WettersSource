function Get-pwGraphAuthorizationHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Tenant,
        [Parameter(Mandatory = $true, ParameterSetName = 'Credman')]
        [string]
        $CredManagerCredentialTarget,
        [Parameter(Mandatory = $true, ParameterSetName = 'Cred')]
        [pscredential]
        $Credential,
        [Parameter(Mandatory = $false)]
        [string]
        $Scope = "https://graph.microsoft.com/.default"
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $CredManCred = Get-StoredCredential -Target $CredManagerCredentialTarget
    $AppRegSecret = [System.Net.NetworkCredential]::new('', $CredManCred.Password).Password
    $Body = @{
        client_id = $CredManCred.UserName
        client_secret = $AppRegSecret
        scope = $Scope
        grant_type = 'client_credentials'
    }
    $GraphUrl = "https://login.microsoftonline.com/$($Tenant).onmicrosoft.com/oauth2/v2.0/token"
    $AuthorizationRequest = Invoke-RestMethod -Uri $GraphUrl -Method "Post" -Body $Body
    
    $Header = @{
        Authorization = $AuthorizationRequest.access_token
        "Content-Type"= "application/json"
    }
    return $Header
}