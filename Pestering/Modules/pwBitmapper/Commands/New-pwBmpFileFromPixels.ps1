function New-pwBmpFileFromPixels {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Pixels,
        [Parameter(Mandatory = $true)]
        $File
    )
    $bmp = Convert-pwPixelstoBmp -Pixels $Pixels
    $bmp.Save("$File")
}
