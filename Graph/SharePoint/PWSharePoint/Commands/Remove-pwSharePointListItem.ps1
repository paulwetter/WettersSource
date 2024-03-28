function Remove-pwSharePointListItem {
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
        [int]
        $ItemId
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $GraphDeleteItem = "https://graph.microsoft.com/v1.0/sites/$SiteID/lists/$ListTitle/items/$ItemId"
    try {
        Invoke-RestMethod -Uri $GraphDeleteItem -Method 'DELETE' -Headers $AuthHeader -ContentType "application/json" -ErrorAction Stop        
    }
    catch {
        throw "Failed to remove item from list.  Error: $_"
    }
}
