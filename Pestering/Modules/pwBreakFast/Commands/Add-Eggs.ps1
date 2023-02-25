function Add-pwEggs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    Write-Verbose "Adding some $Name eggs to the order. Yum!"
}