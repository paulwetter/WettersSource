function Set-pwPropertyMap {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]
        $Mapping,
        [Parameter(Mandatory=$true)]
        [psobject]
        $SourceItem
    )
    $MappedProperties = @{}
    $Properties = ($SourceItem | Get-Member -Type Property).Name
    foreach ($Property in $Properties) {
        If ($Property -in $Mapping.Values) {
            Foreach ($Key in ($Mapping.GetEnumerator() | Where-Object { $_.Value -eq "$Property" }))
            {
                Write-Verbose "Adding [$($Key.name)] with value [$($SourceItem.($Property))]"
                $MappedProperties.Add($Key.name, ($SourceItem.($Property)).ToString())
            }
        } else {
            Write-Verbose "Property [$Property] not found in mapping. Excluding."
        }
    }
    Return $MappedProperties
}
