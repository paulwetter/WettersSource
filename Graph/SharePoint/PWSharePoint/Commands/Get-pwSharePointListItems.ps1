function Get-pwSharePointListItems {
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
        [Parameter(Mandatory=$false)]
        [string[]]
        $Fields
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $GraphGetItems = "https://graph.microsoft.com/v1.0/sites/$SiteID/lists/$ListTitle/items?expand=fields"
    try {
        $Items = Invoke-RestMethod -Uri $GraphGetItems -Method 'GET' -Headers $AuthHeader -ContentType "application/json"
    }
    catch {
        Throw "Unable to get List. Error $_"
    }
    if($Null -ne $FieldMap){
        $UseFields = @()
        Foreach ($f in $Fields){
            $UseFields += $f
        }
        $Items.value.fields | Select-Object $UseFields
    } else {
        $Items.value.fields
    }
}
