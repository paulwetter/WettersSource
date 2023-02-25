function Add-pwPastry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    Write-Verbose "Adding a fresh and delicious $Name pastry to this meal!"
}