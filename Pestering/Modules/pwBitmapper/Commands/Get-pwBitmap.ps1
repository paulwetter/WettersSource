function Get-pwBitmap {
    [OutputType([System.Drawing.Bitmap])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $File
    )
    [System.Drawing.Bitmap]::FromFile("$File")
}