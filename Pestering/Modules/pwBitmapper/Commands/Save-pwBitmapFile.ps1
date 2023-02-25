function Save-pwBitmapFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Drawing.Bitmap]
        $Bitmap,
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )
    $Bitmap.Save("$File")
}