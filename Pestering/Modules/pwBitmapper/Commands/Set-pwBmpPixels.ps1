function Set-pwBmpPixels {
    [OutputType([System.Drawing.Bitmap])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $Pixels,
        [Parameter(Mandatory = $true)]
        [System.Drawing.Bitmap]
        $Bitmap
    )
    foreach ($Pix in $Pixels.GetEnumerator()){
        $xy = $pix.Key
        [int]$x = $xy.split(',')[0]
        [int]$y = $xy.split(',')[1]
        $rgb = $pix.Value
        [int]$R = $rgb.split(',')[0]
        [int]$G = $rgb.split(',')[1]
        [int]$B = $rgb.split(',')[2]
        $color = [System.Drawing.Color]::FromArgb($R, $G, $B)
        Write-debug "Setting Pixel $x, $y"
        $Bitmap.SetPixel($x, $y, $color)            
    }
    return $Bitmap
}