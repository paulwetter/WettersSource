function Invoke-PwPester {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("Path")]
        [string]
        $Script,
        [Parameter(Mandatory=$false)]
        [string]
        $CodeCoverage,
        [Parameter(Mandatory=$false)]
        [int]
        $Version = 5
    )
    try {
        [System.IO.FileInfo]$Script = Convert-Path $Script -ErrorAction Stop
    }
    catch {
        throw "Unable to resolve test script path $Script"
    }
$InvokePesterSplat = @{}
    $PesterConfig = New-PesterConfiguration
    $PesterConfig.Run.Path = $Script.FullName
    $PesterConfig.Output.Verbosity = 'Detailed'
    if ($PSBoundParameters.ContainsKey('CodeCoverage')) {
        $PesterConfig.CodeCoverage.Enabled = $true
        try {
            [System.IO.FileInfo]$CodeCoverage = Convert-Path $CodeCoverage -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to resolve script path for code coverage $CodeCoverage"
            $PesterConfig.CodeCoverage.Enabled = $false
        }
        $PesterConfig.CodeCoverage.CoveragePercentTarget = 80
        $PesterConfig.CodeCoverage.RecursePaths = $false
        $PesterConfig.CodeCoverage.OutputPath = "$($Env:TEMP)\coverage.xml"
        $PesterConfig.CodeCoverage.Path = $CodeCoverage.FullName
    }
    $InvokePesterSplat.Add('Configuration', $PesterConfig)
    Invoke-Pester @InvokePesterSplat
}