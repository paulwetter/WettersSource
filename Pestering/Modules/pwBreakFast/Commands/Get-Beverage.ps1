function Add-pwBeverage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    Write-Verbose "Pouring a fine $Name..."
    If ($Name -eq "Coffee") {
        return "Mug"
    }
    else {
        return "Glass"
    }
}