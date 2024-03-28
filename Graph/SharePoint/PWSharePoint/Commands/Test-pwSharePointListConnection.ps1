function Test-pwSharePointListConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]
        $AuthHeader,
        [Parameter(Mandatory=$true)]
        [guid]
        $SiteId,
        [Parameter(Mandatory=$true)]
        [string]
        $ListTitle
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $GraphGetItems = "https://graph.microsoft.com/v1.0/sites/$SiteID/lists/$ListTitle"
    $List = Invoke-RestMethod -Uri $GraphGetItems -Method 'GET' -Headers $AuthHeader -ContentType "application/json" -ErrorAction SilentlyContinue
    if($Null -eq $List){
        return $false
    } else {
        if ($List.webUrl -like "*$ListTitle*"){
            return $true
        } else {
            return $false
        }
    }
}
