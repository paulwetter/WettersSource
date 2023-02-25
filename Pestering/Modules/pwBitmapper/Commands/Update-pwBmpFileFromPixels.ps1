function Update-pwBmpFileFromPixels {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]        
        $NewPixels,
        [Parameter(Mandatory = $true)]
        [string]
        $File,
        [Parameter(Mandatory = $false)]
        [int]
        $Startx,
        [Parameter(Mandatory = $false)]
        [int]
        $Starty
    )
    $bmp = Copy-pwBitmapImage -File $File
    $MaxPixels = Get-pwPixelMax -Pixels $NewPixels
    Write-Verbose "Size is $($MaxPixels.xMax) x $($MaxPixels.yMax)"
    $Pixels = Move-pwPixels -Pixels $NewPixels -MoveX $Startx -MoveY $Starty
    Write-Verbose "Creating BMP of $($bmp.Height) x $($bmp.Width)"
    $bmp = Set-pwBmpPixels -Pixels $Pixels -Bitmap $bmp
    Save-pwBitmapFile -Bitmap $bmp -File $File
}
