function Set-pwBmpRotate {
    [OutputType([System.Drawing.Bitmap])]
    [CmdletBinding()]
    param (
        [System.Drawing.Bitmap]
        $Bitmap,
        [ValidateSet(90,180,270)]
        [int]$Rotate = 90
    )
    switch ($Rotate) {
        90 { $Bitmap.RotateFlip([System.Drawing.RotateFlipType]::Rotate90FlipNone) }
        180 { $Bitmap.RotateFlip([System.Drawing.RotateFlipType]::Rotate180FlipNone) }
        270 { $Bitmap.RotateFlip([System.Drawing.RotateFlipType]::Rotate270FlipNone) }
    }
    $Bitmap
}
