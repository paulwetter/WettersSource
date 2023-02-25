function New-pwEmptyBitmap {
    [OutputType([System.Drawing.Bitmap])]
    [CmdletBinding()]
    param (
        [int]
        $Width,
        [int]
        $Height
    )
    [System.Drawing.Bitmap]::new($Width, $Height)
}
