function Move-pwPixels {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $Pixels,
        [Parameter(Mandatory = $false)]
        [int]
        $MoveX,
        [Parameter(Mandatory = $false)]
        [int]
        $MoveY
    )
    $newPixels = @{}
    foreach ($Pix in $Pixels.GetEnumerator()){
        $xy = $pix.Key
        [int]$x = $xy.split(',')[0]
        [int]$y = $xy.split(',')[1]
        $x = $x + $MoveX
        $y = $y + $MoveY
        $newPixels.Add("$x,$y", $Pix.Value)
    }
    return $newPixels
}