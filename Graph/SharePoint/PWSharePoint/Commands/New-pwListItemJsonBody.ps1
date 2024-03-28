function New-pwListItemJsonBody {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Properties
    )
    $Body = @{
        fields = @{}
    }
    if ($Properties -is 'HashTable') {
        foreach($PropertyName in $Properties.Keys) {
            $Body.fields.Add("$PropertyName","$($Properties.$PropertyName)")
        }    
    }
    if ($Properties -is 'PSCustomObject'){
        foreach($PropertyName in ($Properties | Get-Member -MemberType NoteProperty).Name) {
            $Body.fields.Add("$PropertyName","$($Properties.$PropertyName)")
        }
    }
    $JsonBody = $Body | ConvertTo-Json -Compress
    return $JsonBody
}
