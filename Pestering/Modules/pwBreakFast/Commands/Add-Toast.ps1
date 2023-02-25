function Add-pwToast {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $Name
    )
    if ([string]::IsNullOrEmpty($Name)){
        Write-Verbose "Looks like you wanted toast but didn't tell us what kind.  So, we'll add a healthy wheat toast"
    } else{
        Write-Verbose "One order of $Name toast coming right up!"
    }
}