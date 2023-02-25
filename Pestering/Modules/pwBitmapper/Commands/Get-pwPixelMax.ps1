function Get-pwPixelMax {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
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
    $xMax = $xMax + 1
    $yMax = $yMax + 1
    Write-Verbose "Get-pwPixelMax found size is $xMax x $yMax"
    return @{
        xMax = $xMax
        yMax = $yMax
    }
}