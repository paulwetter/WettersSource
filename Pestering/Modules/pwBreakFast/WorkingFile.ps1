[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
$bmp = New-Object System.Drawing.Bitmap(240, 240)

for ($i = 0; $i -lt 240; $i++)
{
   for ($j = 0; $j -lt 240; $j += 2)
   {
     $bmp.SetPixel($i, $j, 'Red')
     $bmp.SetPixel($i, $j + 1, [System.Drawing.Color]::FromArgb(0, 100, 200))
   }
}

$bmp.Save("C:\Temp\Test.bmp")
ii f:\Temp\bmp.bmp


function Convert-pwBmpToPixels {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding(DefaultParameterSetName = 'Bitmap')]
    param (
        [Parameter(Mandatory = $true,
        ParameterSetName = 'File')]
        $File,
        [Parameter(Mandatory = $true,
        ParameterSetName = 'Bitmap')]
        [System.Drawing.Image]
        $Bitmap
    )
    if ($PSBoundParameters.Keys.Contains('File')){
        $bmp = [System.Drawing.Bitmap]::FromFile("$File")
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

function New-BmpFileFromPixels {
    [CmdletBinding()]
    param (
        $Pixels,
        $File
    )
    $bmp = Convert-pwPixelstoBmp -Pixels $Pixels
    $bmp.Save("$File")
}

function Convert-pwPixelstoBmp{
    [OutputType([System.Drawing.Image])]
    [CmdletBinding()]
    param (
        $Pixels
    )
    [int]$xMax = 0
    [int]$yMax = 0
    foreach ($pix in $Pixels.GetEnumerator()){
        [int]$x = $pix.Key.split(',')[0]
        [int]$y = $pix.Key.split(',')[1]
        if ($x -gt $xMax) {$xMax = $x}
        if ($y -gt $yMax) {$yMax = $y}
    }
    $xMax++
    $yMax++
    Write-Verbose "Size is $xMax x $yMax"
    $bmp = [System.Drawing.Bitmap]::New($xMax,$yMax)
    Write-Verbose "Creating BMP of $($bmp.Height) x $($bmp.Width)"
    foreach ($pix in $Pixels.GetEnumerator()){
        $xy = $pix.Key
        [int]$x = $xy.split(',')[0]
        [int]$y = $xy.split(',')[1]
        $rgb = $pix.Value
        [int]$R = $rgb.split(',')[0]
        [int]$G = $rgb.split(',')[1]
        [int]$B = $rgb.split(',')[2]
        $color = [System.Drawing.Color]::FromArgb($R, $G, $B)
        $bmp.SetPixel($x, $y, $color)
    }
    $bmp
}

function New-EmptyBitmapFile {
    [CmdletBinding()]
    param (
        [int]
        $Height,
        [int]
        $Width,
        [string]
        $File
    )
    $bmp = [System.Drawing.Bitmap]::new($Width, $Height)
    $bmp.Save("$File")
}

function Update-BmpFileFromPixels {
    [CmdletBinding()]
    param (
        $Pixels,
        [int]$Startx,
        [int]$Starty,
        $File
    )
    $ExistingBmp = [System.Drawing.Bitmap]::FromFile("$File")
    $bmp = [System.Drawing.Bitmap]::new($ExistingBmp)
    $ExistingBmp.Dispose()
    [system.gc]::Collect()
    [int]$xMax = 0
    [int]$yMax = 0
    foreach ($pix in $Pixels.GetEnumerator()){
        [int]$x = $pix.Key.split(',')[0]
        [int]$y = $pix.Key.split(',')[1]
        if ($x -gt $xMax) {$xMax = $x}
        if ($y -gt $yMax) {$yMax = $y}
    }
    $xMax = $xMax++
    $yMax = $yMax++
    Write-Verbose "Size is $xMax x $yMax"
    Write-Verbose "Creating BMP of $($bmp.Height) x $($bmp.Width)"
    foreach ($pix in $Pixels.GetEnumerator()){
        $xy = $pix.Key
        [int]$x = $xy.split(',')[0]
        [int]$y = $xy.split(',')[1]
        $x = $x + $Startx
        $y = $y + $Starty
        $rgb = $pix.Value
        [int]$R = $rgb.split(',')[0]
        [int]$G = $rgb.split(',')[1]
        [int]$B = $rgb.split(',')[2]
        $color = [System.Drawing.Color]::FromArgb($R, $G, $B)
        Write-Verbose "Setting Pixel $x, $y"
        $bmp.SetPixel($x, $y, $color)
    }
    $bmp.Save("$File")
}

function Set-pwBmpRotate {
    [OutputType([System.Drawing.Image])]
    [CmdletBinding()]
    param (
        [System.Drawing.Image]
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

function Add-ToPlate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $ParameterName
    )
}




Update-BmpFromPixels -Pixels $pixels -Startx 120 -Starty 120 -File C:\Temp\Funny.bmp
Update-BmpFromPixels -Pixels $pixels -Startx 0 -Starty 120 -File C:\Temp\Funny.bmp
Update-BmpFromPixels -Pixels $pixels -Startx 120 -Starty 0 -File C:\Temp\Funny.bmp
Update-BmpFromPixels -Pixels $pixels  -File C:\Temp\Funny.bmp
