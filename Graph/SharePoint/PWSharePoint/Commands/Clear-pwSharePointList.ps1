function Clear-pwSharePointList {
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
    $GraphGetItems = "https://graph.microsoft.com/v1.0/sites/$SiteID/lists/$ListTitle/items"
    $Items = Invoke-RestMethod -Uri $GraphGetItems -Method 'GET' -Headers $AuthHeader -ContentType "application/json"
    foreach ($Id in $Items.value.id){
        $GraphDeleteItem = "https://graph.microsoft.com/v1.0/sites/$SiteID/lists/$ListTitle/items/$Id"
        try {
            $null = Invoke-RestMethod -Uri $GraphDeleteItem -Method 'DELETE' -Headers $AuthHeader -ContentType "application/json"
        }
        catch{
            Throw "Failed to remove item from list"
        }
    }
}
