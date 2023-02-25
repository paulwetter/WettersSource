function Add-pwBreakfastMeat {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]
        $Name
    )
    foreach ($Item in $Name) {
        Write-Verbose "Adding a healthy serving of $Item"
    }
}