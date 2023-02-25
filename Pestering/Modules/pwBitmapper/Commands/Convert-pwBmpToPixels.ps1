function Convert-pwBmpToPixels {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding(DefaultParameterSetName = 'Bitmap')]
    param (
        [Parameter(Mandatory = $true,
        ParameterSetName = 'File')]
        $File,
        [Parameter(Mandatory = $true,
        ParameterSetName = 'Bitmap')]
        [System.Drawing.Bitmap]
        $Bitmap
    )
    Write-Verbose "converting bmp to pixels"
    if ($PSBoundParameters.Keys.Contains('File')){
        $bmp = Get-pwBitmap -File $File
    } else {
        $bmp = $Bitmap
    }
    $width = $bmp.Width
    $height = $bmp.Height
    $pixels = @{}
    for ($x = 0; $x -lt $width; $x++) {
        for ($y = 0; $y -lt $height; $y++) {
            $pix = $bmp.GetPixel($x,$y)
            $pixels.Add("$x,$y","$($pix.R),$($pix.G),$($pix.B)")
        }
    }
    $pixels
}
