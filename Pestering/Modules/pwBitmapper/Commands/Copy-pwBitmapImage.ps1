function Copy-pwBitmapImage {
    [OutputType([System.Drawing.Bitmap])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )
    $ExistingBmp = Get-pwBitmap -File $File
    $bmp = [System.Drawing.Bitmap]::new($ExistingBmp)
    $ExistingBmp.Dispose()
    [system.gc]::Collect()
    return $bmp
}