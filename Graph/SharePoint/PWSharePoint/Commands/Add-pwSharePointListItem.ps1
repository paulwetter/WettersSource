function Add-pwSharePointListItem {
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
        $ListTitle,
        [Parameter(Mandatory=$true)]
        [string]
        $ItemJson
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $GraphUrl = "https://graph.microsoft.com/v1.0/sites/$SiteID/lists/$ListTitle/items"
    Invoke-RestMethod -Uri $GraphUrl -Method 'POST' -Body $ItemJson -Headers $AuthHeader -ContentType "application/json"
}
