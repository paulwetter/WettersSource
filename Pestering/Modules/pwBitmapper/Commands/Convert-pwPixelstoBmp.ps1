function Convert-pwPixelstoBmp{
    [OutputType([System.Drawing.Bitmap])]
    [CmdletBinding()]
    param (
        $Pixels
    )
    $Dimensions = Get-pwPixelMax -Pixels $Pixels
    Write-Verbose "Size is $($Dimensions.xMax) x $($Dimensions.yMax)"
    $bmp = New-pwEmptyBitmap -Width $Dimensions.xMax -Height $Dimensions.yMax
    Write-Verbose "Creating BMP of $($bmp.Height) x $($bmp.Width)"
    $bmp = Set-pwBmpPixels -Pixels $Pixels -Bitmap $bmp
    $bmp
}
