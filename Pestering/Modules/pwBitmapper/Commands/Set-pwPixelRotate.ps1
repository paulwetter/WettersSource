function Set-pwPixelRotate {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param (
        $Pixels,
        [ValidateSet(90,180,270)]
        [int]$Rotate = 90
    )
    $bmp = Convert-pwPixelstoBmp -Pixels $Pixels
    $RotatedBmp = Set-pwBmpRotate -Bitmap $bmp -Rotate $Rotate
    Convert-pwBmpToPixels -Bitmap $RotatedBmp
}
